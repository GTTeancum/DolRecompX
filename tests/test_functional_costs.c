/* SPDX-License-Identifier: GPL-3.0-or-later */
#include "cpu/functional_clock_costs.h"
#include "frontend/decoder.h"
#include "backend/functional_clock_opcode_contract.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>

_Static_assert(PPC_OP_COUNT == FC_COST_OPCODE_COUNT, "functional-cost enum count mismatch");
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "cost check failed at %d: %s\n", __LINE__, #x); return 1; } } while (0)

int main(void) {
    CHECK(fc_opcode_cost(PPC_OP_UNKNOWN) == 0);
    for (unsigned op = 1; op < PPC_OP_COUNT; ++op) CHECK(fc_opcode_cost(op) > 0);
    const unsigned invalid[] = {PPC_OP_COUNT, PPC_OP_COUNT + 1, 65535, 0x80000000u, UINT_MAX};
    for (unsigned n = 0; n < sizeof(invalid) / sizeof(invalid[0]); ++n)
        CHECK(fc_opcode_cost(invalid[n]) == 0);
    CHECK(fc_opcode_cost(PPC_OP_ICBI) == 4);
    CHECK(fc_opcode_cost(PPC_OP_DCBZ_L) == 1);
    CHECK(fc_opcode_cost(PPC_OP_DCBZ) == 5);
    CHECK(fc_opcode_cost(PPC_OP_ADDI) == 1);
    CHECK(fc_opcode_cost(PPC_OP_MULLI) == 3);
    CHECK(ppc_decode(0x7c0005ecu, 0x80000000u).op == PPC_OP_UNKNOWN);
    CHECK(strlen(FC_COST_MANIFEST_SHA256) == 64);
    CHECK(strcmp(FC_MODEL_ID, "wii-functional-ppctables-0961ec1-public-v1") == 0);
    puts("PASS: functional costs, unknown rejection and independent decoder boundary");
    return 0;
}
