# The angr Platforms collection

This is a collection of extensions to angr to handle new platforms!

> [!WARNING]  
> Many of the platforms in this repo are better supported using angr's pcode engine.
> We highly reccomend you try using that first if it supports your use case, as angr's pcode engine and pypcode are better maintained and there are more people able to help solve any issues you might encounter.
> This repo sees very little development and we cannot promise that any issues here are addressed in a timely manner.

Here you can find the following:

* ```BrainFuck support (yes, really)``` (by @subwire) Includes a arch description, loader, VEX lifter, native symexec engine, SimOS

* ```TI MSP430 Support``` (by @subwire and @nilocunger) Arch, VEX lifter, SimOS; Uses ELF or Blob to load binaries

* ```Berkeley Packet Filter (BPF)``` (by @ltfish) 

* ```CyberTronix64k support``` (by @rhelmot) Demonstrates how to support arches with odd byte-widths (16-bits), and uses memory-mapped registers and mmio.

* ```[WIP] Atmel AVR support``` (by @subwire, and maybe you!) WIP branch at https://github.com/angr/angr-platforms/tree/wip/avr

* ```[WIP] Hitachi SH4 support``` (by @pwnslinger) https://github.com/angr/angr-platforms/tree/wip/ikaruga

* ```Tricore support``` (by @shahinsba) 

The core idea here is that angr and its components are extensible through _registration_ -- a method, such as `pyvex.lifting.register()` can be used to include your out-of-tree code into angr's automatic consideration.
Through these mechanisms, you can write new architectural descriptions, laoders for new binary formats, lifters for new instruction sets, new simulated execution environments (SimOSes).  You can even create entirely new execution engines that operate on instructions other than the VEX IR.

A set of tutorials, providing a walkthrough of these components, how they interact, and how to write them, can be found here: https://github.com/angr/angr-platforms/tree/master/tutorial

## x86-16 Quick Start

This repo includes an in-tree real-mode DOS sample corpus under `x16_samples/`.

- Decompile a DOS executable directly from the repo root with:
  - `./decompile.py your_binary.exe`
- Decompile a `.COM` sample the same way:
  - `./decompile.py your_binary.com`
- For raw blobs, use:
  - `./decompile.py --blob your_binary.bin`
- If recovery is slow, pass a larger timeout or a concrete function start:
  - `./decompile.py your_binary.exe --timeout 60`
  - `./decompile.py your_binary.exe --addr 0x1146`

- Build or rebuild the sample matrix with `./scripts/build_x16_samples.sh`
- Run the focused x86-16 regression suite with:
  - `../venv/bin/python -m pytest -q tests/test_x86_16_smoketest.py tests/test_x86_16_cod_samples.py tests/test_x86_16_dos_mz_loader.py tests/test_x86_16_sample_matrix.py`
- Run just the real-binary corpus coverage with:
  - `../venv/bin/python -m pytest -q tests/test_x86_16_sample_matrix.py`

The sample rebuild uses the DOS toolchain from `/home/xor/games/f15se2-re` by default. If your toolchain checkout lives somewhere else, set `X16_TOOLCHAIN_ROOT=/path/to/f15se2-re`.
