/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Enumerate synthetic decoder inputs. Never execute guest instructions. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include "frontend/decoder.h"
#include "reference_lookup.h"

static uint64_t counts[PPC_OP_COUNT], total;
static unsigned costs[PPC_OP_COUNT];
static uint32_t first_raw[PPC_OP_COUNT];
static unsigned char seen[PPC_OP_COUNT][REFERENCE_COUNT];

static void require(int condition, const char *message) {
    if (!condition) { fprintf(stderr, "%s\n", message); exit(1); }
}

static void visit(uint32_t raw) {
    const PPCInst inst = ppc_decode(raw, 0x80000000u);
    const unsigned op = (unsigned)inst.op;
    const unsigned ref = reference_lookup[raw >> 26][(raw >> 1) & 1023u];
    require(op < PPC_OP_COUNT && ref < REFERENCE_COUNT, "invalid decoder/reference index");
    if (!counts[op]) first_raw[op] = raw;
    if (op != PPC_OP_UNKNOWN) {
        require(reference_valid[ref] && reference_cost[ref], "known opcode has no positive reference cost");
        require(!counts[op] || costs[op] == reference_cost[ref], "conflicting reference costs for opcode");
        costs[op] = reference_cost[ref];
    }
    seen[op][ref] = 1;
    ++counts[op];
    ++total;
}

int main(void) {
    const unsigned registers[] = {0, 1, 2, 4, 31};
    for (unsigned primary = 0; primary < 64; ++primary)
        for (unsigned sub = 0; sub < 1024; ++sub)
            for (unsigned bit = 0; bit < 2; ++bit)
                for (unsigned d = 0; d < 5; ++d)
                    for (unsigned a = 0; a < 5; ++a)
                        for (unsigned b = 0; b < 5; ++b)
                            visit((primary << 26) | (registers[d] << 21) |
                                  (registers[a] << 16) | (registers[b] << 11) |
                                  (sub << 1) | bit);
    const unsigned spr_xo[] = {339, 371, 467};
    for (unsigned q = 0; q < 3; ++q)
        for (unsigned spr = 0; spr < 1024; ++spr)
            for (unsigned bit = 0; bit < 2; ++bit)
                visit((31u << 26) | (3u << 21) | ((spr & 31u) << 16) |
                      ((spr & 992u) << 6) | (spr_xo[q] << 1) | bit);
    for (unsigned bo = 0; bo < 32; ++bo)
        for (unsigned bi = 0; bi < 32; ++bi)
            for (unsigned lk = 0; lk < 2; ++lk) {
                visit((19u << 26) | (bo << 21) | (bi << 16) | (16u << 1) | lk);
                visit((19u << 26) | (bo << 21) | (bi << 16) | (528u << 1) | lk);
                for (unsigned aa = 0; aa < 2; ++aa)
                    visit((16u << 26) | (bo << 21) | (bi << 16) | (aa << 1) | lk);
            }
    const unsigned psq_primary[] = {56, 57, 60, 61};
    for (unsigned q = 0; q < 4; ++q)
        for (unsigned w = 0; w < 2; ++w)
            for (unsigned index = 0; index < 8; ++index)
                visit((psq_primary[q] << 26) | (3u << 21) | (4u << 16) |
                      (w << 15) | (index << 12));
    require(total == 16398400ULL, "incomplete synthetic enumeration");
    printf("cases %llu\n", (unsigned long long)total);
    for (unsigned op = 0; op < PPC_OP_COUNT; ++op) {
        require(counts[op] != 0, "unobserved decoder enum");
        printf("%u %u %llu %08x", op, costs[op], (unsigned long long)counts[op], first_raw[op]);
        for (unsigned ref = 0; ref < REFERENCE_COUNT; ++ref)
            if (seen[op][ref]) printf(" %u", ref);
        putchar('\n');
    }
    return 0;
}
