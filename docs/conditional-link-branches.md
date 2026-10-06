# Conditional branches with link

For B, BC, BCLR and BCCTR with LK=1, LR receives the address of the following
instruction even when the branch condition is false. BCLR must compute its
target from the old LR, with the low two address bits cleared, before updating
LR. Valid BCCTR forms do not decrement CTR; the decoder rejects those that ask
for that combination. Other conditional branch forms decrement CTR when BO
requires it, including when the CR condition rejects the branch.

The C emitter previously placed conditional LR writes only on taken paths.
The correction makes the write independent of branch outcome while preserving
target capture, local routing, cross-chunk calls and dispatch fallback. The PC
reference test model had the same error and is corrected separately. DolIR
already performs unconditional link updates and is unchanged.

The source-only regression generates synthetic branches, then checks complete
CPU state against raw-word architectural pseudocode. It covers taken/untaken
conditions, BO hints, different CR bit positions, CTR zero/wrap values, LK=0/1,
absolute/relative branches, address wraparound, old-LR target alignment, local
returns, cross-chunk callee/continuation effects and recursion-limit fallback.
Generated test C stays in the build tree. No title data is required.

Primary references:

- [NXP MPC565 Reference Manual, sections 3.7.6 and 3.7.7](https://www.nxp.com/docs/en/data-sheet/MPC565RM.pdf): link updates are independent of branch outcome, and decrementing zero CTR wraps.
- [IBM BCLR/BCLRL instruction](https://www.ibm.com/docs/el/ssw_aix_72/assembler/idalangref_branch_conditional_link_register.html): target alignment, LK and BO behavior.
