#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Regenerate synthetic functional costs from public source and decoder inputs.

Requires a GCC/Clang-compatible host C11 compiler. No network, title files,
historical audit reports, emitted guest C or CPU runtime are used.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile

sys.dont_write_bytecode = True
from reference_tables import ValidationError, parse_decoder_enum, parse_reference, require

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
MODEL_ID = "wii-functional-ppctables-0961ec1-public-v1"
REFERENCE_REVISION = "0961ec1d87a51b7ede57cc4df7629b7f92d0d9d8"
REFERENCE_URL = ("https://github.com/dolphin-emu/dolphin/blob/" + REFERENCE_REVISION +
                 "/Source/Core/Core/PowerPC/PPCTables.cpp")
EXPECTED_CASES = 16_398_400
PINNED_INPUTS = {
    "tools/timing/reference/PPCTables.cpp": "bc6ef549497cb67ebfe3e8d7fbb2e484ec00a0887faccbfa2fd95c8ecc7097df",
    "src/frontend/decoder.h": "27c18a2bf32df9c11e4f7176b94a243bf147a7d10280695e309ca2349a6cf5c0",
    "src/frontend/decoder.c": "8f6e7930089aa25a28762a85b9c4caf75e82dc813a9bfce951428dee2acbfd07",
    "src/common/types.h": "d7280b4787ae7815d143e61942a69f89c4a69c8332599c613a0494bc14b3014d",
}
GENERATOR_INPUTS = ["tools/timing/generate_costs.py", "tools/timing/reference_tables.py",
                    "tools/timing/probe_costs.c"]
MANIFEST = "tools/timing/functional-costs.json"
HEADER = "src/cpu/functional_clock_costs.h"
CONTRACT = "src/backend/functional_clock_opcode_contract.h"
INVENTORY = "tools/timing/functional-costs.sha256"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encode_json(value):
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def verify_inputs(root=ROOT):
    result = {}
    for path, expected in PINNED_INPUTS.items():
        data = (root / path).read_bytes()
        require(sha(data) == expected, "pinned source changed: " + path)
        result[path] = data
    return result


def reference_header(refs, lookup):
    require(all(0 <= r["cycles"] <= 255 for r in refs), "reference cost exceeds header storage")
    text = "#define REFERENCE_COUNT %du\n" % len(refs)
    for name, values in (("reference_cost", [r["cycles"] for r in refs]),
                         ("reference_valid", [int(r["cycles"] > 0 and r["type"] not in
                                                  ("Unknown", "Subtable")) for r in refs])):
        text += "static const unsigned char %s[REFERENCE_COUNT] = {%s};\n" % (
            name, ",".join(map(str, values)))
    text += "static const unsigned short reference_lookup[64][1024] = {\n"
    text += ",\n".join("{" + ",".join(map(str, row)) + "}" for row in lookup)
    return text + "\n};\n"


def parse_probe(text, enum, refs, lookup):
    lines = text.splitlines()
    require(lines and lines[0] == "cases " + str(EXPECTED_CASES), "wrong enumeration count")
    require(len(lines) == len(enum) + 1, "missing or extra decoder enum")
    rows = []
    for line, (name, index) in zip(lines[1:], enum):
        fields = line.split()
        require(len(fields) >= 5, "malformed probe row")
        opcode, cost, count = map(int, fields[:3])
        raw = int(fields[3], 16)
        reference_ids = [int(value) for value in fields[4:]]
        require(opcode == index and count > 0 and 0 <= raw <= 0xffffffff, "invalid probe identity")
        require(reference_ids == sorted(set(reference_ids)) and
                all(0 <= r < len(refs) for r in reference_ids), "invalid reference set")
        require(lookup[raw >> 26][(raw >> 1) & 1023] in reference_ids, "representative selector mismatch")
        if opcode:
            require(0 < cost <= 255 and all(refs[r]["cycles"] == cost and
                    refs[r]["type"] not in ("Unknown", "Subtable") for r in reference_ids),
                    "known opcode lacks a unique positive reference cost")
        else:
            require(cost == 0, "UNKNOWN must be invalid")
        rows.append({"opcode": opcode, "enum": name, "valid": bool(opcode),
                     "modeled_units": cost if opcode else None, "synthetic_case_count": count,
                     "representative_raw": "0x%08x" % raw, "reference_ids": reference_ids})
    require(sum(row["synthetic_case_count"] for row in rows) == EXPECTED_CASES,
            "incomplete per-enum coverage")
    return rows


def enumerate_costs(inputs, probe_source, enum, refs, lookup, compiler):
    with tempfile.TemporaryDirectory(prefix="dolrecomp-costs-") as folder:
        work = Path(folder)
        for path, data in inputs.items():
            if path.startswith("src/"):
                target = work / path
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
        (work / "probe_costs.c").write_bytes(probe_source)
        (work / "reference_lookup.h").write_text(reference_header(refs, lookup))
        executable = work / ("probe.exe" if os.name == "nt" else "probe")
        command = [*compiler, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror", "-pedantic",
                   "-I" + str(work / "src"), "-I" + str(work),
                   str(work / "probe_costs.c"), str(work / "src/frontend/decoder.c"),
                   "-o", str(executable)]
        subprocess.run(command, check=True, capture_output=True, text=True, timeout=120)
        result = subprocess.run([str(executable)], check=True, capture_output=True,
                                text=True, timeout=120)
        return parse_probe(result.stdout, enum, refs, lookup)


def build(root=ROOT, compiler=None):
    data = verify_inputs(root)
    generator_data = {path: (root / path).read_bytes() for path in GENERATOR_INPUTS}
    enum = parse_decoder_enum(data["src/frontend/decoder.h"].decode())
    refs, lookup = parse_reference(data["tools/timing/reference/PPCTables.cpp"].decode())
    compiler = compiler or shlex.split(os.environ.get("CC", "cc"))
    require(bool(compiler), "missing C compiler")
    rows = enumerate_costs(data, generator_data["tools/timing/probe_costs.c"], enum, refs, lookup, compiler)
    for path, content in {**data, **generator_data}.items():
        require((root / path).read_bytes() == content, "source changed during generation: " + path)
    manifest = {
        "schema_version": 1, "model_id": MODEL_ID, "timing_abi_version": 1,
        "model_kind": "static_functional_instruction_cost", "cycle_accurate": False,
        "limitations": ["Pinned reference metadata, not hardware or complete dynamic emulator timing.",
                        "No cache, pipeline, bus, exception or device latency model.",
                        "Synthetic selector coverage is not exhaustive instruction legality.",
                        "A positive cost does not establish semantic success or retirement."],
        "invalid_policy": {"unknown": "reject", "out_of_range": "reject",
                           "embedded_data": "caller_must_reject", "accessor_rejection_sentinel": 0},
        "provenance": {"reference_revision": REFERENCE_REVISION, "reference_url": REFERENCE_URL,
                       "inputs": [{"path": path, "sha256": digest}
                                  for path, digest in sorted(PINNED_INPUTS.items())],
                       "generator_inputs": [{"path": path, "sha256": sha(generator_data[path])}
                                            for path in GENERATOR_INPUTS]},
        "synthetic_enumeration": {"schema": "selectors-registers-spr-branches-psq-v1",
                                  "cases": EXPECTED_CASES, "known_enum_count": len(enum) - 1},
        "reference_entries": refs, "opcodes": rows,
    }
    manifest_bytes = encode_json(manifest)
    digest = sha(manifest_bytes)
    lines = ["/* SPDX-License-Identifier: GPL-3.0-or-later */",
             "/* Generated by tools/timing/generate_costs.py. Do not edit.",
             " * Static functional costs only; zero is rejection, never free execution. */",
             "#ifndef DOLRECOMP_FUNCTIONAL_CLOCK_COSTS_H", "#define DOLRECOMP_FUNCTIONAL_CLOCK_COSTS_H", "",
             '#define FC_MODEL_ID "' + MODEL_ID + '"',
             '#define FC_COST_MANIFEST_SHA256 "' + digest + '"',
             "#define FC_TIMING_ABI_VERSION 1u", "#define FC_COST_OPCODE_COUNT %du" % len(enum), "",
             "static inline unsigned fc_opcode_cost(unsigned opcode) {",
             "    static const unsigned char costs[FC_COST_OPCODE_COUNT] = {"]
    lines += ["        %du, /* %d: %s */" % (row["modeled_units"] or 0, row["opcode"], row["enum"])
              for row in rows]
    lines += ["    };", "    return opcode < FC_COST_OPCODE_COUNT ? costs[opcode] : 0u;",
              "}", "", "#endif", ""]
    header_bytes = "\n".join(lines).encode("ascii")
    contract = ["/* SPDX-License-Identifier: GPL-3.0-or-later */",
                "/* Generated enum contract. Include after decoder.h and functional_clock_costs.h. */",
                "#ifndef DOLRECOMP_FUNCTIONAL_CLOCK_OPCODE_CONTRACT_H",
                "#define DOLRECOMP_FUNCTIONAL_CLOCK_OPCODE_CONTRACT_H"]
    contract += ['_Static_assert(%s == %du, "functional cost enum mismatch: %s");' %
                 (name, number, name) for name, number in enum]
    contract += ['_Static_assert(PPC_OP_COUNT == FC_COST_OPCODE_COUNT, "functional cost enum count mismatch");',
                 "#endif", ""]
    outputs = {MANIFEST: manifest_bytes, HEADER: header_bytes,
               CONTRACT: "\n".join(contract).encode("ascii")}
    outputs[INVENTORY] = "".join(sha(content) + "  " + path + "\n"
                                  for path, content in outputs.items()).encode("ascii")
    return outputs


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="verify generated bytes without writing")
    compilers = parser.add_mutually_exclusive_group()
    compilers.add_argument("--cc", help="GCC/Clang-compatible host C11 compiler command")
    compilers.add_argument("--cc-path", help="literal host C11 compiler path, including spaces")
    args = parser.parse_args()
    try:
        compiler = [args.cc_path] if args.cc_path else shlex.split(args.cc) if args.cc else None
        outputs = build(compiler=compiler)
        for path, data in outputs.items():
            target = ROOT / path
            if args.check:
                require(target.read_bytes() == data, "stale generated artifact: " + path)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(data)
    except (ValidationError, OSError, ValueError, subprocess.SubprocessError) as error:
        print("Cost generation rejected: " + str(error), file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError):
            print(error.stderr, file=sys.stderr)
        return 1
    print("Verified 236 known costs over 16,398,400 synthetic decoder cases; UNKNOWN invalid.")
    print("Cost manifest SHA256: " + sha(outputs[MANIFEST]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
