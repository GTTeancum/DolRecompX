/* SPDX-License-Identifier: GPL-3.0-or-later */
/* Links only the small provider adapter, without clock state, costs or tracing. */
#include "experimental/clock_contract.h"
#include <stdio.h>

static unsigned calls;
static int refuse;
static FcResult read_full(void *context, uint32_t cia, uint32_t reg, uint64_t *out) {
    (void)context; (void)cia; (void)reg; ++calls;
    *out=UINT64_C(0x12345678abcdef01);
    return refuse ? FC_ERR_REFUSED : FC_OK;
}
static FcResult write_half(void *context, uint32_t cia, uint32_t reg, uint32_t value, uint64_t *out) {
    (void)context; (void)cia; (void)reg; (void)value; ++calls;
    *out=UINT64_C(0x9988776655443322);
    return refuse ? FC_ERR_REFUSED : FC_OK;
}
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"contract line %d: %s\n",__LINE__,#x); return 1; } } while (0)
int main(void) {
    FcProvider provider={FC_PROVIDER_ABI_VERSION,&calls,read_full,write_half};
    uint64_t shadow=UINT64_C(0xaabbccddeeff0011);
    uint32_t value=77;
    CHECK(fc_provider_validate(0)==FC_OK);
    provider.abi=0;
    CHECK(fc_provider_validate(&provider)==FC_ERR_PROVIDER);
    CHECK(fc_provider_read_shadow(&provider,&shadow,0,268,&value)==FC_ERR_PROVIDER && !calls && value==77);
    CHECK(fc_provider_write_shadow(&provider,&shadow,0,284,1)==FC_ERR_PROVIDER && !calls);
    provider.abi=FC_PROVIDER_ABI_VERSION;
    CHECK(fc_provider_validate(&provider)==FC_OK);
    CHECK(fc_provider_read_shadow(&provider,&shadow,0,268,&value)==FC_OK);
    CHECK(value==0xabcdef01 && shadow==UINT64_C(0x12345678abcdef01) && calls==1);
    refuse=1; value=77;
    CHECK(fc_provider_read_shadow(&provider,&shadow,0,269,&value)==FC_ERR_REFUSED);
    CHECK(value==77 && shadow==UINT64_C(0x12345678abcdef01));
    CHECK(fc_provider_write_shadow(&provider,&shadow,0,284,1)==FC_ERR_REFUSED);
    CHECK(shadow==UINT64_C(0x12345678abcdef01));
    refuse=0;
    CHECK(fc_provider_write_shadow(&provider,&shadow,0,284,1)==FC_OK);
    CHECK(shadow==UINT64_C(0x9988776655443322));
    provider.read_full=0;
    CHECK(fc_provider_validate(&provider)==FC_ERR_PROVIDER);
    provider.write_half=0;
    CHECK(fc_provider_validate(&provider)==FC_OK);
    CHECK(fc_provider_read_shadow(&provider,&shadow,0,269,&value)==FC_OK && value==0x99887766);
    CHECK(fc_provider_write_shadow(0,&shadow,0,285,5)==FC_OK && shadow==UINT64_C(0x0000000555443322));
    CHECK(fc_provider_read_shadow(0,&shadow,0,270,&value)==FC_ERR_PROVIDER);
    CHECK(fc_provider_write_shadow(0,&shadow,0,286,1)==FC_ERR_PROVIDER);
    puts("PASS: isolated versioned provider contract and refusal nonmutation");
    return 0;
}
