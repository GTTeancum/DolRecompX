# Public-source functional instruction costs

This optional metadata capability defines static instruction costs. It does not
enable a guest clock, change CPUState, alter emitted code, or replace the existing
fail-closed timebase policy. Costs do not establish successful execution,
retirement, hardware latency or cycle-accurate emulator behavior.

The model is `wii-functional-ppctables-0961ec1-public-v1`. Its identity includes
the exact generated manifest SHA256. All 236 known decoder enum values have one
positive reference cost. UNKNOWN and out-of-range indices return zero, which is
a rejection sentinel; callers must reject them before effects. Embedded data
must be rejected separately. ICBI costs 4 in this model; existing scheduling
budgets are unchanged. DCBZ_L and DCBZ retain distinct costs of 1 and 5.

## Reproduction

From the repository root, using Python 3 and a GCC/Clang-compatible host C11
compiler:

```sh
python3 tools/timing/generate_costs.py --cc clang
python3 tools/timing/generate_costs.py --cc clang --check
python3 tests/test_functional_cost_manifest.py --cc clang -v
sha256sum -c tools/timing/functional-costs.sha256
```

The generator compiles only the decoder and a synthetic metadata probe. It
enumerates 16,398,400 raw-word combinations: primary and subopcode selectors,
bit 0, register fields in {0,1,2,4,31}, SPR/TBR selectors, branch controls and PSQ
fields. It rejects absent enums, nonpositive or conflicting known-opcode costs,
invalid reference classes and stale input pins. No guest instructions execute.
This is coverage of the stated synthetic domain, not all 2^32 encodings or an
instruction-legality proof.

The manifest contains only public source provenance, repo-relative source
hashes, generator hashes, reference table metadata and freshly enumerated
synthetic rows. No title files, old measurement reports or generated modules are
inputs. Regeneration from a relocated allowlisted source tree must be identical.
Updating decoder or reference pins requires reviewing and revalidating the cost
mapping; the generator refuses silent source drift.

## Provenance and limits

`tools/timing/reference/PPCTables.cpp` is an unchanged source snapshot from
[Dolphin revision 0961ec1d87a51b7ede57cc4df7629b7f92d0d9d8](https://github.com/dolphin-emu/dolphin/blob/0961ec1d87a51b7ede57cc4df7629b7f92d0d9d8/Source/Core/Core/PowerPC/PPCTables.cpp).
It retains Copyright 2008 Dolphin Emulator Project and its GPL-2.0-or-later
notice. The decoder and new integration use the repository's GPL-3.0-or-later
terms. The snapshot is parsed as metadata; Dolphin is not linked into the probe.

This identity is separate from any earlier experimental manifest, even when
numeric costs agree. Do not relabel older objects, profiles or admission records
with it. Clock/provider integration, per-instruction retirement, event-domain
admission and production timing remain separate work. This metadata capability
alone makes no image-size claim toward the complete resident-XBE target.

The generated opcode-contract header pins every named enum index for consumers
of the numeric table. The portable C test includes it even where the Python
regeneration test is unavailable. Host regeneration snapshots the verified
decoder inputs into a temporary tree and rejects concurrent source changes.
