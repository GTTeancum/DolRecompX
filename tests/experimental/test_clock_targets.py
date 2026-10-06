#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Cross-check the bounded synthetic oracle; optional i386 execution and nxdk compilation.

Outputs are local evidence, never source inputs. No SDK changes, title data,
guest code generation, firmware or emulator boot are involved.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
SOURCES = ["src/experimental/functional_clock.c", "src/experimental/provider_adapter.c",
           "tests/experimental/test_functional_clock.c"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--clang", default="clang", help="literal Clang executable path")
    parser.add_argument("--gcc", help="optional literal GCC executable path")
    parser.add_argument("--qemu", help="optional literal qemu-i386 executable path")
    parser.add_argument("--nxdk", type=Path, help="optional existing nxdk tree; compile-only")
    parser.add_argument("--llvm-readobj", default="llvm-readobj")
    args = parser.parse_args()
    out = args.output.resolve()
    out.mkdir(parents=True, exist_ok=True)
    # A failed rerun must never leave an earlier successful report admissible.
    report_path = out / "report.json"
    report_path.write_text(json.dumps({"passed": False, "status": "in_progress"}) + "\n")
    commands, observations = [], []

    def run(name, command, environment=None):
        result = subprocess.run(command, env=environment, text=True, capture_output=True, timeout=120)
        (out / (name + ".log")).write_text(result.stdout + result.stderr)
        commands.append({"name": name, "command": command, "exit_code": result.returncode})
        if result.returncode:
            raise RuntimeError(name + " failed:\n" + result.stdout + result.stderr)
        return result.stdout

    run("vectors", [sys.executable, str(ROOT / "tools/timing/generate_arithmetic_vectors.py"),
                    "--output", str(out / "arithmetic_vectors.h")])
    flags = ["-std=c11", "-Wall", "-Wextra", "-Werror", "-I" + str(ROOT / "src"), "-I" + str(out)]
    sources = [str(ROOT / source) for source in SOURCES]
    variants = [("clang-O0", args.clang, "-O0", []), ("clang-Oz", args.clang, "-Oz", []),
                ("sanitized-O0", args.clang, "-O0", ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]),
                ("sanitized-Oz", args.clang, "-Oz", ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"])]
    if args.gcc:
        variants += [("gcc-O0", args.gcc, "-O0", []), ("gcc-Os", args.gcc, "-Os", [])]
    for name, compiler, optimization, extra in variants:
        executable = out / name
        run(name + "-build", [compiler, *flags, optimization, *extra, *sources, "-o", str(executable)])
        observations.append(run(name + "-run", [str(executable)]).strip())
    if args.qemu:
        for optimization in ("O0", "Oz"):
            name = "i386-" + optimization
            executable = out / name
            run(name + "-build", [args.clang, *flags, "-" + optimization, "--target=i386-linux-gnu",
                                  "-march=pentium3", "-ffreestanding", "-fno-builtin", "-fno-stack-protector",
                                  "-fno-pie", "-nostdlib", "-static", "-DFC_FREESTANDING", "-fuse-ld=lld",
                                  *sources, str(ROOT / "tests/experimental/clock_i386_runner.c"),
                                  str(ROOT / "tests/experimental/clock_i386_start.S"), "-o", str(executable)])
            observations.append(run(name + "-run", [args.qemu, "-cpu", "pentium3", str(executable)]).strip())
    imports = {}
    if args.nxdk:
        sdk = args.nxdk.resolve()
        environment = dict(os.environ, NXDK_DIR=str(sdk), PATH=str(sdk / "bin") + os.pathsep + os.environ["PATH"])
        for optimization in ("O0", "Oz"):
            for source in sources:
                name = "nxdk-" + optimization + "-" + Path(source).stem
                obj = out / (name + ".obj")
                run(name + "-build", [str(sdk / "bin/nxdk-cc"), *flags, "-" + optimization,
                                      "-DFC_FREESTANDING", "-c", source, "-o", str(obj)], environment)
                symbols = run(name + "-inspect", [args.llvm_readobj, "--file-headers", "--symbols", str(obj)])
                if "IMAGE_FILE_MACHINE_I386" not in symbols:
                    raise RuntimeError(name + " did not produce an i386 COFF object")
                for forbidden in ("__udivdi3", "__divdi3", "__muldi3", "__aulldiv", "__allmul", "__aullrem",
                                  "__lshrdi3", "__ashldi3", "__ashrdi3"):
                    if forbidden in symbols:
                        raise RuntimeError(name + " imports unsupported arithmetic helper " + forbidden)
                imports[name] = re.findall(r"Name: (\S+)[^}]*?Section: IMAGE_SYM_UNDEFINED", symbols, re.S)
    if not observations or len(set(observations)) != 1 or not re.fullmatch(r"PASS checks=\d+ digest=[0-9a-f]{16}", observations[0]):
        raise RuntimeError("Synthetic target results disagree: " + repr(observations))
    report = {"passed": True, "result": observations[0], "runtime_variants": len(observations),
              "i386_qemu_executed": bool(args.qemu), "nxdk_compile_only": bool(args.nxdk),
              "xbox_hardware_tested": False, "title_data_used": False, "commands": commands,
              "nxdk_undefined_symbols": imports,
              "source_sha256": {source: hashlib.sha256((ROOT / source).read_bytes()).hexdigest() for source in SOURCES}}
    report_path.write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps({key: value for key, value in report.items() if key not in ("commands", "source_sha256", "nxdk_undefined_symbols")}, indent=2))


if __name__ == "__main__":
    main()
