# Reusable Xbox optimization pipeline

DolRecompX is a reusable static-recompilation and optimization pipeline.
An individual title is a validation workload, not the implementation boundary.
Compiler decisions must come from decoded instructions, control-flow analysis
and explicit configuration, with title-independent synthetic regression tests.
Do not embed title addresses, traces, assets or generated code in the toolchain.

The current Xbox design target is roughly 6 MiB for the complete resident
native image. This is a target, not a measured result or a memory-fit claim.
Account for all translated code, native helpers, descriptors, dispatch tables,
runtime and SDK image sections. All recompiled code must remain in the XBE;
an external code pack or omission of unobserved code does not meet the target.
Guest RAM, stack, heap, graphics, audio and other runtime allocations require
separate accounting against actual available physical memory.

## Optimization acceptance

- Implement reusable transformations in the compiler/emitter, rather than
  depending on title-specific postprocessing of generated C.
- Give every emission policy a stable identity in the generator and chunk
  hashes; include compiler version, flags, ABI and dependencies in object keys.
- Preserve legal entry coverage, control-flow semantics, memory callbacks,
  floating-point behavior and supported instrumentation boundaries.
- Test baseline and optimized output on synthetic instruction/control-flow
  cases, including failure paths and the target calling convention.
- Verify complete static-link coverage and mapped image size before reporting
  a reduction. File size alone is insufficient.
- Keep full-title measurement and execution evidence private. A synthetic
  pass, smaller link or bounded diagnostic stop is not a gameplay result.

The opt-in i386 memory-helper ABI and downstream machine outlining are
incremental experiments. They are not evidence that the complete-image target
has been reached. Large reductions require structural code-generation work,
with separate correctness, size and eventual target-performance measurements.

The optional [timebase policy](timebase-policy.md) is a correctness boundary.
Optimization must preserve it; inventing guest time to advance a diagnostic is
not a valid size or performance optimization.
