# Opt-in verified pure-DAG recovery, v1

A generic, default-off, offline analysis library over the current repository’s
actual DolIR. It does not enable rewrites in the production compiler. There is no title-specific selector, address/hash recognition, opcode
histogram, timing change, interpreter, runtime solver, or native-ABI promise.

## Scope and API

`src/analysis/verified_idioms/verified_idioms.h` exposes:

- `discover(const DolIRFunction&, Options)`: read-only automatic structural
  discovery. `Options.enabled` defaults to false. A subtraction-shaped DAG with
  a low-bit/multiple-of-power-of-two mask, or an arithmetic shift/left-shift
  rounded multiple, proposes `SRemPow2{input, input_type, output_type, power}`.
  Recognition is independent of source names, addresses and instruction words.
- `verify(function, candidate)`: reconstruct the normalized DAG and every
  admission-relevant provenance field, then prove root equality to typed
  `bvsrem` (and optional low-bit truncation). A saved UNSAT/status flag is never
  accepted as authority.
- `apply(function, candidate, RegionContract, Options)`: an explicit opt-in
  local rewrite. It freshly runs FunctionCertificationv1 using the caller's
  trusted evidence checker, requires closed entry/effect/observation/CFG
  obligations bound to exact source/contract identity, and replays the SMT
  proof. Missing, stale, malformed, forged or unsupported evidence fails closed.
- `emitRecoveredC` / `emitRecoveredLLVM`: emit the small typed expression as C
  remainder or LLVM `srem`, without alias, readonly, nounwind, or overflow flags.
  These are pure-expression artifact emitters, not whole-function backends.

The first input scope is 32- and 64-bit actual state-read SSA inputs. Positive
signed powers `2^k`, for `0 <= k < input_bits - 1`, and output truncations to
1/8/16/32/64 bits (no wider than the input) are supported. Arithmetic, masks,
constant-valued shifts/rotates, integer comparisons, selects and integer casts
are translated with bitvector semantics. Dynamic and potentially oversize
ordinary shifts, floating point, PHIs and effectful DAG dependencies reject.
The positive divisor range makes the lowered signed division defined even for
signed minimum. Unsupported cases remain original IR with explicit reasons.

## Actual PPC builder projection and its trust boundary

The driver and tests use the unchanged `ppc_decode` / `dolir_build_chunk`.
The builder produces one original source block per PPC instruction. Read-only
projection follows consecutive, single-internal-predecessor fallthrough edges,
tracks exact reaching GPR writes and repeated unchanged GPR reads, and records
all source blocks and forwarding edges needed by a candidate. Nonlinear edges,
internal merges and unknown/effectful services reset forwarding. CR/XER and
other potentially aliased architectural state are not forwarded.

A unique internal predecessor does **not** prove no external/interior entry,
exception resumption or observer mutation. Projected candidate equivalence is
therefore conditional: the SMT proof establishes the pure projected equation;
it does not prove the projection's environmental assumptions. The report
explicitly marks this limitation. Every original source cut and state write
still exists. No assumption becomes a compiler attribute.

V1 refuses **all cross-cut or reaching-state-projected lowering**, including
when a controlled synthetic function certificate is closed. Upstream currently
has no validated cross-block SSA transport/lowering contract. This is a
specific `CROSS_CUT_LOWERING_NOT_IMPLEMENTED` result, not a request to relax
entry or observation requirements. Discovery on a real corpus can legitimately
yield no unconditional, safely rewritable candidates.

## What an admitted local rewrite preserves

An admitted single-block pure DAG root is lowered into existing DolIR
`CONSTANT / SDIV / MUL / SUB`, with optional `TRUNC`. The original root SSA ID
is retained. All other original instructions, including intermediate pure
values with other consumers, state writes, helper/memory effects, and source
block/terminator/raw/cycle metadata are retained verbatim. The proposed arrays are first checked as a staged DolIRModule; validator refusal frees staging and leaves original ownership and source bytes unchanged. There is no DCE,
block merging, materialization elision, source-cut pruning or body-size claim.
The original root's full field encoding remains in the candidate certificate.
Default discovery/application leaves output byte-for-byte unchanged.

## Proof and implementation identity

Each proof records the exact replayable QF_BV query and SHA-256, solver version,
loaded solver-library SHA-256, build-time semantic implementation SHA-256,
solver result/proof or counterexample output, original-source fingerprint,
source-cut fingerprint and normalized DAG fingerprint. Source fingerprints
reuse FunctionCertificationv1's canonical encoding.

The implementation identity is embedded at build time, not looked up from a
source path at runtime. A missing build identity refuses proof. The current
optional adapter loads Linux `libz3.so.4`; unavailable solver/identity, unknown,
error and timeout cannot authorize a rewrite. Timeout must be 1..60000 ms;
the default is 10000 ms. Node/candidate/source-size budgets are bounded.
Proof mode is configured before context creation. The direct solver API checks
parse/result errors and retrieves a complete proof or counterexample before
reporting success; unavailable proof evidence refuses the candidate. Solver
check timeout is set explicitly on each QF_BV solver. Shared-DAG proof output (`z3-shared-proof-dag.v1`) retains each node once;
its complete final root and reference closure are checked. Counterexamples use
`smtlib2-model.v1` with checked form structure and model-declaration counts.
Both reject prefix truncation, with an 8 MiB post-retrieval text limit.
This limit does not bound the solver's internal allocation or printing time.
Completeness checks detect lost output; they do not implement a separate proof
calculus. The solver remains trusted, and independent tests replay the saved
canonical SMT query.

The trusted checker callback is an explicit host trust boundary, not a
cryptographic signature scheme. A production host must independently validate
the exact environment/entry/observation obligations against the source and
contract. The positive test checker is only for its controlled synthetic
invocation and has no authority over arbitrary code or captured inputs.

## Build and reproduce

Default configure does not enable C++ or look for crypto/SMT dependencies:

    cmake -S . -B build-disabled

Enable the Linux-only offline adapter explicitly:

    cmake -S . -B build-cmake -DDOLRECOMP_ENABLE_VERIFIED_IDIOMS=ON
    cmake --build build-cmake -j2
    ctest --test-dir build-cmake --output-on-failure

It reuses the repository’s certification and shared DolIR/native-analysis
libraries. OpenSSL Crypto and C++17 are build-time dependencies only when
enabled; Z3 is an offline runtime dependency of the analysis tool. No LLVM
development package is required. The small C/LLVM expression differential test
uses an available Clang executable, independently of the production backend.

Read-only discovery accepts any caller-selected contiguous hexadecimal PC/raw
listing and writes reports only to the specified directory:

    build-cmake/discover_words input.words report-directory

Synthetic differential tests compile four pure-expression implementations:
original typed DolIR to unsigned-defined C and LLVM test lowerers, and recovered
C and LLVM `srem`. They compare boundary values, signed minima and deterministic
random inputs against an independent mathematical remainder oracle:

    CLANG=clang python3 tests/function_pipeline/differential.py build-cmake/idiom-evidence

The dedicated test lowerers are not the full upstream production C/LLVM
backends. These checks do not claim whole-guest execution or native ABI safety.
Generic tests/artifacts belong here; private corpus inputs and reports must
remain in a separate caller-owned directory.

Replay all saved local equivalence queries independently with a bounded solver:

    python3 tests/function_pipeline/replay.py build-cmake/idiom-evidence/all-proofs --expected-count 468

The integrated implementation ID is emitted even when discovery finds no
candidate. It comes from `function-pipeline-identity.json`, not a hardcoded
source revision or runtime source-file lookup. All semantic sources, transitive
public headers and identity/build recipes participate in watched dependencies.
Saved proofs from a previous implementation are never relabeled as current.

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
