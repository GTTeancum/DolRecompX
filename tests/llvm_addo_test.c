/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "cpu/cpu.h"
#include "addo_cases.h"
#include <stdio.h>
#include <string.h>

#define DECLARE(pc,n,d,a,b,rc,d2,a2,b2,rc2) void func_##pc(CPUState* cpu);
DOLIR_ADDO_CASES(DECLARE)
#undef DECLARE
#define ENTRY(pc,n,d,a,b,rc,d2,a2,b2,rc2) func_##pc,
static void (*const native_addo[])(CPUState*) = { DOLIR_ADDO_CASES(ENTRY) };
#undef ENTRY
static u32 random_state = 0x65A24E19u;
static u32 fallback_count;
static u32 random32(void) {
    random_state ^= random_state << 13;
    random_state ^= random_state >> 17;
    random_state ^= random_state << 5;
    return random_state;
}
static void refused_fallback(CPUState* cpu, u32 raw, u32 cia) {
    (void)raw;
    fallback_count++;
    cpu->pc = cia + 4u;
}

/* Independent sign-bit equation; the builder uses a widened signed sum. */
static void reference_addo(CPUState* cpu, const DolirAddoOperands* op) {
    const u32 a = cpu->gpr[op->a], b = cpu->gpr[op->b], result = a + b;
    const u32 overflow = (~(a ^ b) & (a ^ result)) >> 31;
    cpu->gpr[op->d] = result;
    cpu->xer = (cpu->xer & ~0x40000000u) | (overflow ? 0xC0000000u : 0);
    if (op->rc) {
        const u32 field = (result >> 31 ? 8u : result ? 4u : 2u) | (cpu->xer >> 31);
        cpu->cr = (cpu->cr & 0x0FFFFFFFu) | (field << 28);
    }
}

int main(void) {
    static const u32 boundaries[] = {0, 1, 2, 0x7FFFFFFEu, 0x7FFFFFFFu,
        0x80000000u, 0x80000001u, 0xFFFFFFFEu, 0xFFFFFFFFu,
        0x40000000u, 0xC0000000u, 0x0000FFFFu};
    CPUState cpu, initial, expected;
    if (!cpu_init(&cpu)) return 1;
    cpu.instruction_fallback = refused_fallback;
    memcpy(&initial, &cpu, sizeof(cpu));
    unsigned cases = 0, overflow_results = 0, cleared_ov = 0, retained_so = 0, recorded_new_so = 0;
    const unsigned edges = sizeof(boundaries) / sizeof(boundaries[0]);
    for (unsigned form = 0; form < sizeof(dolir_addo_cases) / sizeof(dolir_addo_cases[0]); form++) {
        const DolirAddoCase* test = &dolir_addo_cases[form];
        for (unsigned flags = 0; flags < 8; flags++) {
            for (unsigned vector = 0; vector < edges * edges + 128; vector++) {
                memcpy(&cpu, &initial, sizeof(cpu));
                for (unsigned r = 0; r < 32; r++) {
                    cpu.gpr[r] = random32();
                    const u64 bits = ((u64)random32() << 32) | random32();
                    memcpy(&cpu.fpr[r], &bits, sizeof(bits));
                    memcpy(&cpu.ps1[r], &bits, sizeof(bits));
                }
                cpu.gpr[2] = 0;
                cpu.gpr[test->ops[0].a] = vector < edges * edges ? boundaries[vector / edges] : random32();
                cpu.gpr[test->ops[0].b] = vector < edges * edges ? boundaries[vector % edges] : random32();
                cpu.xer = (random32() & 0x1FFFFFFFu) | (flags << 29);
                cpu.cr = random32();
                cpu.ctr = random32();
                cpu.fpscr = random32();
                cpu.timebase = ((u64)random32() << 32) | random32();
                cpu.pc = test->pc;
                cpu.lr = 0x81234567u;
                cpu.downcount = 1000;
                memcpy(&expected, &cpu, sizeof(cpu));
                for (unsigned n = 0; n < test->count; n++) {
                    const u32 old_xer = expected.xer;
                    reference_addo(&expected, &test->ops[n]);
                    overflow_results += !!(expected.xer & 0x40000000u);
                    cleared_ov += !!(old_xer & 0x40000000u) && !(expected.xer & 0x40000000u);
                    retained_so += !!(old_xer & 0x80000000u) && !(expected.xer & 0x40000000u);
                    recorded_new_so += test->ops[n].rc && !(old_xer & 0x80000000u) && !!(expected.xer & 0x80000000u);
                }
                expected.gpr[29] = expected.xer;
                expected.gpr[30] = expected.cr;
                expected.pc = expected.lr & ~3u;
                expected.downcount -= test->count + 3u;
                native_addo[form](&cpu);
                if (fallback_count || memcmp(&cpu, &expected, sizeof(cpu))) {
                    fprintf(stderr, "ADDO mismatch form=%u flags=%u vector=%u fallback=%u\n", form, flags, vector, fallback_count);
                    cpu_free(&cpu);
                    return 2;
                }
                cases++;
            }
        }
    }
    cpu_free(&cpu);
    if (!overflow_results || !cleared_ov || !retained_so || !recorded_new_so) return 3;
    printf("ADDO native full-state cases: %u\n", cases);
    return 0;
}
