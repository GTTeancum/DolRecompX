# Optional C-backend timebase policy

`CPUState.timebase_access` lets a host reject an architecturally legal timebase
access before its register or timebase storage changes. This is an access
policy, not a clock provider. A null callback retains standalone storage
behavior; a returning callback permits that access; a rejecting callback must
not return. Hosts without a guest clock can use a nonlocal diagnostic stop.

MFTB and MFSPR reads of 268/269 invoke the policy in either privilege mode.
Supervisor MTSPR writes of 284/285 also invoke it. Illegal encodings and
privileged writes in user mode retain their original exception precedence and
do not invoke the policy. The callback receives the original instruction
address, register, direction and write value (zero for reads).

`cpu_reset` preserves the callback. It is appended to CPUState, so existing
field offsets remain unchanged, but every generated-code and runtime consumer
must be rebuilt. The module descriptor's state-size gate rejects the previous
layout. Do not reuse objects from an older CPU ABI.

The C emitter routes these operations through the CPU helpers. The LLVM
backend has separate timing emission and does not enforce this callback; a
host requiring this policy must use the C backend until LLVM policy support is
implemented and tested. The callback neither advances time nor changes code
coverage, dispatch budgeting or optimization selection.

Legality reference: IBM Gekko User's Manual v1.2, Table 2-52 and note 2
(printed pages 2-62 and 2-63), which permit user-readable MFSPR 268/269 as well
as MFTB and supervisor MTSPR 284/285:
https://doc.kodewerx.org/documents/gekko_user_manual.pdf
