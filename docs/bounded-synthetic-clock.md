# Bounded synthetic clock oracle

This default-off experimental capability checks functional clock and provider
contracts independently of a CPU or generated module. Enable it explicitly:

```sh
cmake -S . -B build-clock -DDOLRECOMP_ENABLE_SYNTHETIC_CLOCK=ON
cmake --build build-clock --parallel 2
ctest --test-dir build-clock --output-on-failure
```

It adds `dr_clock_provider` and `dr_synthetic_clock`, plus three tests. Neither
library is linked into `dolrecomp`, `dr_cpu`, a generated module or the Xbox
runtime. CPUState, code emission and the existing timebase safety policy remain
unchanged. These are experimental contracts, not a production timing ABI.

## Separate contract and implementation

`experimental/clock_contract.h` contains result values and a versioned paired
provider contract. It has no clock state, event queue, diagnostic trace, cost
table, CPU layout or allocator dependency. The provider adapter can be linked
and tested by itself. A null provider uses caller-owned stored timebase; a
non-null provider must identify the exact provider ABI and supply both callbacks
or neither. Callbacks must produce the complete 64-bit result on success.
Refusal may record terminal/error diagnostics, but must not commit timebase,
anchor or other architectural effects. The adapter cannot roll back arbitrary
provider-context changes. Shadow/register outputs commit only after success.

The caller still owns legality, privilege, policy checks and callback lifetime.
Provider context is not assumed to be disjoint from CPU or guest state.
The required order is legality/privilege, existing access policy, paired
provider, then shadow update. No CPU integration is supplied by this stage.

`experimental/functional_clock.h` is a separate bounded reference implementation.
Its fixture has explicit core and timing ABI versions, the new public cost-model
ID/digest, synthetic-only declaration and every event-domain declaration. Old
experimental fixtures and identities are not interchangeable. No production
backend is required to adopt this representation, per-instruction C API or
diagnostic storage layout.
Rebuild consumers together; these C structures are not a serialized state format
or a cross-target layout contract.

## Reference semantics and limits

- Begin and successful retirement are separate. An attempted/refused instruction
  consumes no completed units; partial effects are diagnosed without rollback.
- The timebase advances by one tick per 12 completed model units, with checked
  elapsed-unit arithmetic and modulo-2^64 timebase rollover. Writes re-anchor
  the complete timebase and reset the fractional phase.
- Instruction-budget slicing does not change the completed state or event trace.
- Supported synthetic events are serviced in deadline/sequence order. All due
  supported events drain before a due unsupported-domain sentinel stops the
  boundary. This is the oracle's explicit contract, not real-device scheduling.
- Real domains have unsupported sentinels only. There is no invented device
  completion, interrupt delivery, boot fixture or host-time substitution.
- The fixed queue contains 32 entries and the never-evicted trace 512 entries.
  Begin/retire alone exhaust it after at most 256 instructions; accesses and
  events consume more entries. Capacity exhaustion stops before the next effect.
- The state occupies about 54 KiB on verified x64, and initialization uses another
  full temporary on the stack. It is a test oracle, not a production memory plan.
  nxdk objects require ordinary compiler/runtime imports such as `__chkstk` and
  `memcpy`; they are not import-free.

## Synthetic proof

The arithmetic test generates 12,468 independent Python big-integer vectors into
the build tree. No generated vector blob is committed. The C tests cover
rollover, provider halves and rejection, precise attempt/retirement state,
capacity/overflow boundaries, event replacement/cancellation, slice invariance,
ABI refusal, null pointers and isolated provider linking.

Optional host/sanitizer and i386 checks use existing tools:

```sh
python3 tests/experimental/test_clock_targets.py --output build-clock/targets \
  --clang clang --gcc gcc --qemu qemu-i386 --nxdk /path/to/existing/nxdk
```

Omit `--qemu` or `--nxdk` when unavailable. nxdk is compile-only; QEMU executes a
freestanding synthetic Linux/i386 runner using a Pentium III CPU profile. Neither
is Xbox hardware or title execution. The script does not install or change an
SDK. Sanitizer settings are caller-controlled; if leak detection cannot run in a
ptrace-based environment, disclose any local `ASAN_OPTIONS=detect_leaks=0` override.

Structural native-code optimization, exact CPU integration and production event
admission require separate designs and proofs. This capability makes no size,
performance, gameplay or roughly 6 MiB complete-resident-XBE claim.
