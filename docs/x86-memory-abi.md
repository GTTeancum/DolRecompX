# Experimental 32-bit x86 memory-helper ABI

Defining `DOLRECOMP_X86_FASTCALL=1` changes only `mem_read8/16/32/64` and
`mem_write8/16/32/64`. Every caller and the CPU implementation must use the
same definition. The default remains the existing calling convention.
CPUState layout, generated game source and external/SDK callback types do not
change. Opt-in on non-i386 targets is rejected at preprocessing time.

On 32-bit Clang x86, fastcall passes the first two eligible arguments in ECX
and EDX and uses callee stack cleanup for the remaining arguments. This can
reduce repeated call-site setup; it is not proof of an execution speedup.
Reference: https://releases.llvm.org/17.0.1/tools/clang/docs/AttributeReference.html#fastcall

PE/COFF decorates these symbols differently, so unresolved mixed-convention
calls fail linking. ELF does not provide that protection: build all callers
and callees with identical options, and keep revision/flag gates on caches.
Function-pointer users must preserve the declared calling convention.

The corresponding ModernGekkoX `--memory-abi fastcall` builder option is an
experiment, not a change to the SDK ABI. Its synthetic tests exercise actual
cpu.c memory helpers across separate i386 objects, including 64-bit values,
RAM aliases, callbacks and reservation behavior. QEMU testing is not original
Xbox hardware execution or whole-game numerical/performance validation.
