/* SPDX-License-Identifier: GPL-3.0-or-later */
.global _start
.type _start,@function
_start:
    andl $-16, %esp
    call runner_main
    movl %eax, %ebx
    movl $1, %eax
    int $0x80
.section .note.GNU-stack,"",@progbits
