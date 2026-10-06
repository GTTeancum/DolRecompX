#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate an independent, deterministic big-integer oracle into the build tree."""
import argparse
from pathlib import Path
import random


def generate():
    rng = random.Random(0x46434c31)
    maximum = (1 << 64) - 1
    cases = []
    for phase in range(12):
        for completed in (0, 1, 11, 12, 13, 40, (1 << 32) - 1, 1 << 32,
                          (1 << 63) - 1, 1 << 63, maximum - 12, maximum - 1, maximum):
            for base in (0, (1 << 32) - 1, maximum):
                cases.append((completed, 0, base, phase))
    for _ in range(12000):
        completed = rng.getrandbits(64)
        cases.append((completed, rng.randrange(completed + 1), rng.getrandbits(64), rng.randrange(12)))
    lines = ["/* SPDX-License-Identifier: GPL-3.0-or-later */",
             "/* Generated independent Python big-integer oracle; synthetic inputs only. */",
             "typedef struct { uint64_t c,a,b; uint32_t p; uint64_t want; } OracleVector;",
             "static const OracleVector oracle_vectors[] = {"]
    for completed, anchor, base, phase in cases:
        expected = (base + (completed - anchor + phase) // 12) & maximum
        lines.append("{UINT64_C(0x%x),UINT64_C(0x%x),UINT64_C(0x%x),%d,UINT64_C(0x%x)}," %
                     (completed, anchor, base, phase, expected))
    lines.append("};\n")
    return "\n".join(lines).encode("ascii")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(generate())
    print("Generated 12,468 synthetic arithmetic vectors")


if __name__ == "__main__":
    main()
