# Experimental Function Certification v1

A reusable, opt-in, read-only pass over actual DolRecompX DolIR. It does not emit or modify code, set LLVM attributes, alter ABI flags, infer production function boundaries, prune entries, or change timing. There is no complete-native image or size claim.

## Build and run

Requirements when enabled: C/C++17 compiler, CMake 3.16+, OpenSSL Crypto development library. LLVM is not required. The pass reuses the current repository’s `dr_ir`, `dr_frontend` and shared native-liveness support; no copied compiler snapshot is built.

```sh
cmake -S . -B build -DDOLRECOMP_ENABLE_FUNCTION_CERTIFICATION=ON
cmake --build build -j4
ctest --test-dir build --output-on-failure
printf '1000 38600001 4e800020\n' | build/certify_words
```

With certification, idioms and LLVM omitted/OFF, configuration remains C-only and does not find OpenSSL or a solver. No analysis targets are created. The analysis libraries are not linked into the normal compiler, CPU runtime or generated modules. Existing production behavior remains unchanged.

The driver reads one region per line: `<start_hex> <word_hex> ...`. It imports with actual `ppc_decode` and `dolir_build_chunk`, verifies actual DolIR, and emits one JSON result per line, including malformed input and importer failures. Unknown decodes are counted, preserved as fallback instructions, and remain OPEN. The driver has no option to manufacture trusted evidence, infer function boundaries, or read pointer-looking data as immutable memory.

## API and trust boundary

`src/analysis/function_certification/function_certification.h` exposes:

- `sourceFingerprint(function)`: canonical SHA256 of all proof-relevant source fields, including source cuts, raw words, guest PCs, cycle costs, typed instructions, state masks and terminators. Pointers, capacities and diagnostic name are excluded. The caller must supply actual allocated DolIR arrays. Structural/hard-limit failures return an empty string; arbitrary invalid native pointers are outside a C++ API's validation ability.
- `contractFingerprint(contract)`: canonical identity of source, sorted unique entry set, exact observation model, evidence obligations, immutable word contents and analysis budgets.
- `certify(function, contract)`: bounded conservative analysis, returning a fresh `Certificate`.
- `toJson(certificate)`: report format `dolrecomp.function-certification.v1`. A serialized report is never authority to rewrite.

The pass does not prove the completeness of real-world entry populations, code immutability, asynchronous routes or observer behavior. Those facts require an independent trusted evidence checker. `Verified` plus a label is merely a claim: without a matching successful `verify_evidence` callback it cannot produce CLOSED. The callback receives exact source and contract identities, entry set, model, obligation, evidence identifier and, for immutable words, address/value. It must check the actual claim, not recognize a label. It is part of the explicitly trusted kernel; malicious or mistaken checker approval cannot be repaired by this pass. Exceptions from a checker are rejected conservatively.

The synthetic tests supply a deliberately bounded closed-world environment. That verifier is not a production verifier. Production or private raw-source input without an independent environment proof remains OPEN.

## Status semantics

- CLOSED: the specific dimension is proved by the analysis under externally checked contracts and the documented DolIR model. Aggregate CLOSED is the conjunction of entry, CFG/resume, effect, return and observation dimensions.
- CONDITIONAL: otherwise discharged obligations depend on explicit claims that are not independently checked. It does not authorize a rewrite.
- OPEN: invalid input, unsupported analysis, unresolved entry/transfer/effect/observation, exhausted budget or absent evidence. Unknowns are retained, never treated as impossible.

An intraprocedural return fact can be CLOSED while overall entry/observer closure is OPEN. It says only that a transfer reachable from the declared region invocation carries symbolic incoming LR (or incoming LR masked with `~3u`). It does not prove whole-program function discovery. Region membership and speculative boundaries remain distinct from checked entry closure.

## Implemented analysis

- Actual DolIR CFG/terminators, preserving conditional taken and fallthrough alternatives when the condition is unknown. Constant conditions permit reporting a proved feasible edge; no source edge or block is removed.
- Monotone architectural-state provenance: exact integer constants, selected exact integer operations, GPR/LR/CTR copies, incoming LR, and masked incoming LR. Other architectural slots deliberately lose provenance, including packed/virtual CR and XER fields. SSA operands must be local to a source block for this version; cross-block/forward SSA reports OPEN.
- Register save/restore of incoming LR when actual dataflow proves it. Unknown calls, helpers and unproved memory services clobber all architectural provenance; no guest ABI or stack-save convention is assumed.
- Constant-derived local indirect edges, including copied function-pointer constants. Unknown indirects conservatively feed unknown state to every region block and retain an unresolved exterior transfer.
- Immutable U32 loads only with checked exact contents, all-alias/all-writer lifetime exclusion, and plain nonfaulting/nonobserving read evidence. Neither an address-domain annotation nor a data-section word is proof. Any store, opaque helper, linked call, fallback or exception anywhere in the source prevents immutable-load use in v1. Cross-block address derivation is conservatively unsupported for these loads.
- Complete conservative typed MAY summaries for represented execution and transitive transfers. Opaque services/tails/indirects/exceptions widen to TOP, including all state, RAM, MMIO/FIFO, fault/partial phases, callbacks, host bindings, reservation, coherence, timing, mode and exception/resume effects. Refusal before commit, returning exception and terminal partial effect are explicitly separate obligations. Unknown arithmetic partiality (division, unbounded/overshift) remains OPEN. The summary assumes only the explicitly reported invocation model; missing global entry/resume/observer facts remain separate OPEN dimensions.
- Existing `dolllvm_analyze_function_abi` runs unchanged as an explicitly advisory baseline. Its support flags and current helper masks never confer certification. The original call-liveness source is available in the foundations library for integration; v1 does not use its narrower results to discard state.
- Conservative semantic live-ins and may-written live-outs. Per-block live-in/live-out and preservation/materialization masks retain all architectural state because the exact/current observer model may inspect it at every original cut. Packed CR/XER and virtual field aliases are widened. Architectural PC and downcount controller updates are included. These are sound upper bounds, not minimal liveness or a code-size optimization.

CLOSED is relative to abstract DolIR architectural state primitives and the checked exact-cut environment. It does not certify actual emitter state-service callbacks or admit a production ABI.

`native_abi_plan.eligible` describes only whether this bounded certificate permits planning under its checked model. It is not existing emitter admission and does not modify native ABI flags. All original cut costs/order and full-state materialization remain requirements. Termination is not proved; loops can be CLOSED structurally while termination stays false. Guest-stack elision is always false.

## Limits and validation

Hard maxima are 4,096 blocks, 1,000,000 instructions and 1,000,001 SSA values; caller budgets can only tighten them. The default block/value product is bounded to 16,000,000 and worklist/edge counts to 1,000,000 each. No callee-summary composition, recursion proof, guest-stack alias proof, general memory-effect contract, exception/resume lowering, whole-program entry proof, state materializer, code generator, or production runtime integration is implemented. Unsupported positive cases remain OPEN. No interpreter or sidepack is introduced. Native resident-image feasibility and any target size remain unproved.

The local test suite contains positive/negative structural tests and deterministic constant-operation property cases. Independent synthetic and separately predeclared private-source review are owned outside this clean source tree. Private source bytes, case addresses, title metadata and per-case reports must not be copied into public artifacts.

A later automatic rewrite must freshly certify the exact source with a trusted checker, require every relevant dimension CLOSED, independently prove its typed mathematical equivalence, preserve all exported roots/effects/source cuts and exact timing, and revalidate the result. Math equivalence or a JSON CLOSED field alone is insufficient.

## Integrated build identity

`function-pipeline-identity.json` in the build directory records distinct
certification and idiom implementation identities. The recipe binds all current
public source/header bytes, both build recipes, compiler versions, target
architecture, build flags and optional LLVM enable/version configuration.
Selected compiler/crypto binary bytes and available OpenSSL headers are bound
as well. This identifies documented build inputs, not a hermetic attestation
of the host, runtime loader or all compiler/system transitive dependencies.
The analysis itself consumes no LLVM development headers or libraries. CMake watches both
file contents and source/header additions or removals. Labels are repository
relative; relocation alone does not relabel otherwise identical builds.

These identities are intentionally distinct from prior isolated experiments.
No fixed Git revision or external source-directory override substitutes for
the actual compiled inputs. A JSON report is still not rewrite authority.

### Resource and evidence failures

Canonical serialization uses the classic locale and refuses stream failures.
SHA-256 provider failures and C++ allocation failures propagate as exceptions;
callers must treat these as refusal, never substitute an empty identity or a
previous proof. File-writing drivers return failure if output cannot be fully
written and closed. A failed run may leave incomplete files and is not evidence.
The optional idiom mutation constructs and structurally verifies a temporary
result and its complete fingerprint before transferring ownership. Exceptions
or refusals preserve the original source arrays and values. Synthetic tests
inject one-shot allocation failures across serialization, proof replay and
application, as well as a failing cryptographic provider.
