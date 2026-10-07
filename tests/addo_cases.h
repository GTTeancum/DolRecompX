/* SPDX-License-Identifier: GPL-3.0-or-later */
#ifndef DOLRECOMP_TEST_ADDO_CASES_H
#define DOLRECOMP_TEST_ADDO_CASES_H
#include <stdint.h>

/* Synthetic entry, count, then destination/source/source/Rc for two operations. */
#define DOLIR_ADDO_CASES(X) \
    X(80005200, 1, 5,3,4,0, 0,0,0,0) \
    X(80005220, 1, 3,3,4,0, 0,0,0,0) \
    X(80005240, 1, 4,3,4,0, 0,0,0,0) \
    X(80005260, 1, 5,3,3,0, 0,0,0,0) \
    X(80005280, 1, 3,3,3,0, 0,0,0,0) \
    X(800052A0, 1, 0,0,4,0, 0,0,0,0) \
    X(800052C0, 1, 31,3,31,0, 0,0,0,0) \
    X(800052E0, 1, 31,0,0,0, 0,0,0,0) \
    X(80005300, 1, 5,3,4,1, 0,0,0,0) \
    X(80005320, 1, 3,3,4,1, 0,0,0,0) \
    X(80005340, 1, 4,3,4,1, 0,0,0,0) \
    X(80005360, 1, 5,3,3,1, 0,0,0,0) \
    X(80005380, 1, 3,3,3,1, 0,0,0,0) \
    X(800053A0, 1, 0,0,4,1, 0,0,0,0) \
    X(800053C0, 1, 31,3,31,1, 0,0,0,0) \
    X(800053E0, 1, 31,0,0,1, 0,0,0,0) \
    X(80005400, 2, 5,3,4,0, 10,2,2,1) \
    X(80005420, 2, 3,3,4,1, 10,2,2,0)

typedef struct { uint8_t d, a, b, rc; } DolirAddoOperands;
typedef struct { uint32_t pc, count; DolirAddoOperands ops[2]; } DolirAddoCase;
#define ADDO_ROW(pc,n,d,a,b,rc,d2,a2,b2,rc2) \
    {0x##pc##u,n,{{d,a,b,rc},{d2,a2,b2,rc2}}},
static const DolirAddoCase dolir_addo_cases[] = { DOLIR_ADDO_CASES(ADDO_ROW) };
#undef ADDO_ROW
#endif
